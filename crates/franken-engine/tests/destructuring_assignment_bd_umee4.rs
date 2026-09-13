//! bd-umee4 — array destructuring assignment to existing lvalues.
//!
//! `[a, b] = [b, a]` (and `[x, y] = arr`, member targets, nesting) was rejected
//! at lowering with FE-LOWER-ASSIGN-0001 ("assignment to non-lvalue target").
//! The lowering Assignment arm now handles an `ArrayLiteral` target: the RHS is
//! evaluated once into a temp (so swaps read pre-assignment values) and each
//! element target is assigned from `temp[index]` (identifier/member targets reuse
//! existing paths; nested array patterns recurse). The expression evaluates to
//! the RHS, per ES2020 §13.15.5.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

// ---- bead pin: swap ------------------------------------------------------

#[test]
fn swap_first() {
    assert_eq!(eval("let a = 1; let b = 2; [a, b] = [b, a]; a;"), "2");
}

#[test]
fn swap_second() {
    assert_eq!(eval("let a = 1; let b = 2; [a, b] = [b, a]; b;"), "1");
}

// ---- basic destructuring -------------------------------------------------

#[test]
fn basic_first() {
    assert_eq!(eval("let x = 0; let y = 0; [x, y] = [10, 20]; x;"), "10");
}

#[test]
fn basic_second() {
    assert_eq!(eval("let x = 0; let y = 0; [x, y] = [10, 20]; y;"), "20");
}

// ---- member-expression element target ------------------------------------

#[test]
fn member_target() {
    assert_eq!(eval("let o = { p: 0 }; [o.p] = [9]; o.p;"), "9");
}

// ---- nested array pattern (recurses) -------------------------------------

#[test]
fn nested_inner() {
    assert_eq!(eval("let a = 0; let b = 0; [[a], b] = [[1], 2]; a;"), "1");
}

#[test]
fn nested_outer() {
    assert_eq!(eval("let a = 0; let b = 0; [[a], b] = [[1], 2]; b;"), "2");
}

// ---- elision / hole skips the slot ---------------------------------------

#[test]
fn hole_is_skipped() {
    assert_eq!(eval("let a = 0; let c = 0; [a, , c] = [1, 2, 3]; c;"), "3");
}

// ---- the assignment expression evaluates to the RHS ----------------------

#[test]
fn result_is_rhs() {
    assert_eq!(eval("let a = 0; let b = 0; ([a, b] = [7, 8])[1];"), "8");
}

fn assert_assignment(source: &str, expected: &str) {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(source)
        .unwrap_or_else(|error| panic!("{error}\n{source}"));
    assert_eq!(outcome.value, expected, "source: {source}");
}

#[test]
fn defaults_assign_left_to_right() {
    assert_assignment(
        r#"let a = 0, b = 0; [a = 3, b = a + 2] = []; a + ':' + b;"#,
        "3:5",
    );
}

#[test]
fn default_does_not_replace_null_zero_or_false() {
    assert_assignment(
        r#"let a, b, c, d, calls = 0; [a = ++calls, b = ++calls, c = ++calls, d = ++calls] = [null, 0, false]; (a === null) + ':' + b + ':' + (c === false) + ':' + d + ':' + calls;"#,
        "true:0:true:1:1",
    );
}

#[test]
fn default_gets_source_element_only_once() {
    assert_assignment(
        r#"let reads = 0, a; let source = []; Object.defineProperty(source, '0', {get() { reads += 1; return undefined; }}); [a = 9] = source; reads + ':' + a;"#,
        "1:9",
    );
}

#[test]
fn default_member_reference_is_not_recomputed_after_initializer() {
    assert_assignment(
        r#"let first = {}, second = {}, target = first; [target.x = (target = second, 7)] = []; first.x + ':' + (second.x === undefined);"#,
        "7:true",
    );
}

#[test]
fn default_member_reference_precedes_element_getter() {
    assert_assignment(
        r#"let trace = '', target = {}; function base() { trace += 'b'; return target; } function key() { trace += 'k'; return 'x'; } let source = []; Object.defineProperty(source, '0', {get() { trace += 'g'; return undefined; }}); [base()[key()] = (trace += 'd', 9)] = source; trace + ':' + target.x;"#,
        "bkgd:9",
    );
}

#[test]
fn nested_defaults_assign_all_levels_without_replacing_rhs_result() {
    assert_assignment(
        r#"let a, b, source = []; let result = ([[a = 7, b = a + 1] = []] = source); (result === source) + ':' + a + ':' + b;"#,
        "true:7:8",
    );
}

#[test]
fn rest_assigns_all_remaining_elements() {
    assert_assignment(
        r#"let head, tail; [head, ...tail] = [1, 2, 3]; head + ':' + tail.join(':');"#,
        "1:2:3",
    );
}

#[test]
fn nested_rest_assignment_writes_each_target() {
    assert_assignment(r#"let a = 0, b = 0; [...[a, b]] = [4, 5]; a + b;"#, "9");
}

#[test]
fn rest_assignment_combines_nested_defaults_and_member_targets() {
    assert_assignment(
        r#"let target = {}, a = 0; [a, ...[target.x = a + 1, target.y = target.x + 1]] = [7]; a + ':' + target.x + ':' + target.y;"#,
        "7:8:9",
    );
}

#[test]
fn rest_member_reference_is_preserved_during_tail_getters() {
    assert_assignment(
        r#"let first = {}, second = {}, target = first; let source = [1]; Object.defineProperty(source, '0', {get() { target = second; return 8; }}); [...target.x] = source; first.x[0] + ':' + (second.x === undefined);"#,
        "8:true",
    );
}

#[test]
fn assignment_result_is_the_unmodified_original_rhs() {
    assert_assignment(
        r#"let a, b, calls = 0, source = [1, 2, 3]; function rhs() { calls += 1; return source; } let result = ([a, ...b] = rhs()); b[0] = 99; (result === source) + ':' + calls + ':' + source.join(':');"#,
        "true:1:1:2:3",
    );
}

#[test]
fn throwing_default_keeps_earlier_writes_and_skips_later_targets() {
    assert_assignment(
        r#"let a = 0, b = 0, c = 0; function boom() { throw 'stop'; } try { [a = 1, b = boom(), c = 3] = []; } catch (e) {} a + ':' + b + ':' + c;"#,
        "1:0:0",
    );
}

#[test]
fn default_const_assignment_evaluates_initializer_before_throwing() {
    assert_assignment(
        r#"const a = 1; let calls = 0, error = ''; try { [a = (calls += 1, 9)] = []; } catch (e) { error = e.name; } a + ':' + calls + ':' + error;"#,
        "1:1:TypeError",
    );
}

#[test]
fn rest_const_assignment_is_catchable() {
    assert_assignment(
        r#"const a = 1; let error = ''; try { [...a] = [2, 3]; } catch (e) { error = e.name; } a + ':' + error;"#,
        "1:TypeError",
    );
}

#[test]
fn assignment_to_tdz_binding_remains_catchable() {
    assert_assignment(
        r#"let error = ''; try { [a = 2] = []; let a; } catch (e) { error = e.name; } error;"#,
        "ReferenceError",
    );
}

#[test]
fn strict_unresolvable_default_target_keeps_original_reference() {
    // ECMA-262 IteratorDestructuringAssignmentEvaluation evaluates lRef before
    // the initializer. This is a normative test, not a V8-output fixture:
    // local Node currently re-resolves the newly created global and returns 9.
    assert_assignment(
        r#"'use strict'; let error = ''; try { [absent = (globalThis.absent = 1, 9)] = []; } catch (e) { error = e.name; } error + ':' + globalThis.absent;"#,
        "ReferenceError:1",
    );
}

#[test]
fn sloppy_unresolvable_default_target_creates_realm_binding() {
    assert_assignment(r#"[created = 8] = []; globalThis.created;"#, "8");
}

#[test]
fn rest_elisions_preserve_tail_offset() {
    assert_assignment(
        r#"let a, tail; [a, , ...tail] = [1, 2, 3, 4]; a + ':' + tail.join(':');"#,
        "1:3:4",
    );
}

#[test]
fn default_assignment_rhs_reads_old_target_values_once() {
    assert_assignment(
        r#"let a = 1, b = 2, tail; [a, b = a, ...tail] = [b, undefined, a]; a + ':' + b + ':' + tail[0];"#,
        "2:2:1",
    );
}
