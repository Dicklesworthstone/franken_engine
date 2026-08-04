//! Regression coverage for bd-p89tp: a closure's assignment to a captured outer
//! `let` must persist to the outer binding. Before bd-x0ld5, module bindings and
//! closure captures used disconnected register/scope copies, so a counter
//! closure never incremented the value observed by the enclosing code
//! (`inc(); inc(); c` stayed 0). Exact canonical capture cells now make both
//! sides observe the same live binding.
//! bd-it65u extends that proof to deferred parents which mutate bindings already
//! captured by child closures while preserving the register path for true locals.
//!
//! Value-asserting through HybridRouter::eval.

use frankenengine_engine::HybridRouter;

fn eval_value(src: &str) -> String {
    let mut engine = HybridRouter::default();
    engine
        .eval(src)
        .unwrap_or_else(|e| panic!("eval failed for {src:?}: {e}"))
        .value
}

#[test]
fn arrow_closure_writes_back_to_captured_let() {
    // The bead's pin.
    assert_eq!(
        eval_value("let c = 0; let inc = () => c = c + 1; inc(); inc(); c;"),
        "2"
    );
    assert_eq!(
        eval_value("let c = 0; let inc = () => c = c + 1; inc(); c;"),
        "1"
    );
}

#[test]
fn function_expression_closure_writes_back() {
    assert_eq!(
        eval_value("let c = 0; let inc = function() { c = c + 1; }; inc(); inc(); inc(); c;"),
        "3"
    );
}

#[test]
fn compound_assign_in_closure_writes_back() {
    // += through a closure to the captured outer let.
    assert_eq!(
        eval_value("let c = 0; let inc = () => c += 1; inc(); inc(); c;"),
        "2"
    );
}

#[test]
fn counter_factory_accumulates() {
    // Closure over a factory-local binding accumulates across calls.
    assert_eq!(
        eval_value(
            "let make = function() { let n = 0; return function() { n = n + 1; return n; }; }; let f = make(); f(); f();"
        ),
        "2"
    );
}

#[test]
fn outer_write_is_visible_to_preexisting_closure() {
    assert_eq!(
        eval_value("let x = 1; let read = () => x; x = 2; read();"),
        "2"
    );
}

#[test]
fn deferred_function_assignment_updates_outer_capture() {
    assert_eq!(
        eval_value("let hits = 0; function record() { hits = hits + 1; } record(); hits;"),
        "1"
    );
}

#[test]
fn deferred_parent_updates_reach_preexisting_child_capture() {
    assert_eq!(
        eval_value(concat!(
            "function make() { let n = 1; let read = () => n; ",
            "n += 2; n++; return read; } make()();"
        )),
        "4"
    );
}

#[test]
fn deferred_local_assignment_keeps_register_path() {
    assert_eq!(
        eval_value(
            "function updateLocal() { let n = 1; n = n + 2; n++; return n; } updateLocal();"
        ),
        "4"
    );
}

#[test]
fn equal_factory_activations_keep_distinct_bindings() {
    assert_eq!(
        eval_value(concat!(
            "let make = function() { let n = 0; ",
            "return function() { n = n + 1; return n; }; }; ",
            "let a = make(); let b = make(); a(); ",
            "let aSecond = a(); let bFirst = b(); aSecond + ':' + bFirst;"
        )),
        "2:1"
    );
}

#[test]
fn sibling_closures_share_only_their_factory_activation_bd_e7t2b() {
    assert_eq!(
        eval_value(concat!(
            "function make(x) { return [() => x, value => x = value]; } ",
            "let a = make(1); let b = make(2); a[1](9); ",
            "a[0]() + ':' + b[0]();"
        )),
        "9:2"
    );
}

#[test]
fn closure_observes_later_same_scope_initialization() {
    assert_eq!(
        eval_value("let read = function() { return x; }; let x = 42; read();"),
        "42"
    );
}

#[test]
fn iterator_cleanup_write_is_visible_to_scope_and_existing_closure() {
    assert_eq!(
        eval_value(concat!(
            "let cleanupCalled = false; let observe = () => cleanupCalled; ",
            "let customIterable = { [Symbol.iterator]() { let count = 0; ",
            "return { next() { return { value: count++, done: false }; }, ",
            "return() { cleanupCalled = true; return { done: true }; } }; } }; ",
            "for (let value of customIterable) { break; } ",
            "(cleanupCalled ? 10 : 0) + (observe() ? 1 : 0);"
        )),
        "11"
    );
}

#[test]
fn named_function_expression_does_not_replace_outer_same_named_binding() {
    assert_eq!(
        eval_value("let g = 7; let read = () => g; let f = function g() { return 0; }; read();"),
        "7"
    );
}

#[test]
fn class_method_creation_does_not_replace_outer_same_named_binding() {
    assert_eq!(
        eval_value(
            "let method = 9; let read = () => method; class C { method() { return 0; } } read();"
        ),
        "9"
    );
}

#[test]
fn classic_for_let_closures_get_distinct_iteration_cells_inside_function() {
    assert_eq!(
        eval_value(concat!(
            "let run = function() { let a; let b; let c; ",
            "for (let i = 0; i < 3; i++) { ",
            "if (i === 0) { a = () => i; } ",
            "else if (i === 1) { b = () => i; } else { c = () => i; } } ",
            "return a() + b() + c(); }; run();"
        )),
        "3"
    );
}

#[test]
fn classic_for_continue_renews_binding_before_update() {
    assert_eq!(
        eval_value(concat!(
            "let a; let b; let c; for (let i = 0; i < 3; i++) { ",
            "if (i === 0) { a = () => i; continue; } ",
            "if (i === 1) { b = () => i; continue; } c = () => i; } ",
            "a() + b() + c();"
        )),
        "3"
    );
}

#[test]
fn closures_from_same_iteration_share_one_cell() {
    assert_eq!(
        eval_value(concat!(
            "let write; let read; for (let i = 0; i < 1; i++) { ",
            "write = () => i = 7; read = () => i; } write(); read();"
        )),
        "7"
    );
}

#[test]
fn for_of_let_closures_get_distinct_iteration_cells() {
    assert_eq!(
        eval_value(concat!(
            "let a; let b; let c; for (let value of [0, 1, 2]) { ",
            "if (value === 0) { a = () => value; } ",
            "else if (value === 1) { b = () => value; } else { c = () => value; } } ",
            "a() + b() + c();"
        )),
        "3"
    );
}

#[test]
fn for_of_const_closures_get_distinct_iteration_cells() {
    assert_eq!(
        eval_value(concat!(
            "let a; let b; let c; for (const value of [0, 1, 2]) { ",
            "if (value === 0) { a = () => value; } ",
            "else if (value === 1) { b = () => value; } else { c = () => value; } } ",
            "a() + b() + c();"
        )),
        "3"
    );
}

#[test]
fn for_of_destructuring_default_initializes_fresh_const_cell() {
    assert_eq!(
        eval_value("let read; for (const [value = 7] of [[]]) { read = () => value; } read();"),
        "7"
    );
}

#[test]
fn nested_for_of_destructuring_default_initializes_fresh_let_cell() {
    assert_eq!(
        eval_value(concat!(
            "function make() { let read; for (let [value = 7] of [[]]) { ",
            "read = () => value; } return read; } make()();"
        )),
        "7"
    );
}
